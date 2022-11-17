package org.sonar.samples.java.checks;

import static org.sonar.java.checks.helpers.ReassignmentFinder.getInitializerOrExpression;
import static org.sonar.java.checks.helpers.ReassignmentFinder.getReassignments;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.Nullable;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.Tree.Kind;

@Rule(key = "CMICSQLInjectionCheckCustomRule")
public class CMICSQLInjectionCheckCustomRule extends IssuableSubscriptionVisitor {
	private static final String JAVA_SQL_CALLABLESTATEMENT = "java.sql.CallableStatement";
	private static final String MAIN_MESSAGE = "Make sure using a dynamically formatted SQL query is safe here. This is CMIC Message ";

	@Override
	public List<Kind> nodesToVisit() {
		// TODO Auto-generated method stub
		return Collections.singletonList(Tree.Kind.CLASS);
	}

	private static final MethodMatchers SQL_INJECTION_SUSPECTS = MethodMatchers.or(

			MethodMatchers.create().ofSubTypes(JAVA_SQL_CALLABLESTATEMENT)
					.names("executeQuery", "execute", "executeUpdate", "executeLargeUpdate", "addBatch")
					.withAnyParameters().build());

	@Override
	public void visitNode(Tree tree) {
		if (anyMatch(tree)) {
			Optional<ExpressionTree> sqlStringArg = arguments(tree)
					.filter(arg -> arg.symbolType().is("java.lang.String")).findFirst();

			if (sqlStringArg.isPresent()) {
				ExpressionTree sqlArg = sqlStringArg.get();
				if (isDynamicConcatenation(sqlArg)) {
					reportIssue(sqlArg, MAIN_MESSAGE);
				} else if (sqlArg.is(Tree.Kind.IDENTIFIER)) {
					IdentifierTree identifierTree = (IdentifierTree) sqlArg;
					Symbol symbol = identifierTree.symbol();
					ExpressionTree initializerOrExpression = getInitializerOrExpression(symbol.declaration());
					List<AssignmentExpressionTree> reassignments = getReassignments(symbol.owner().declaration(),
							symbol.usages());

					if ((initializerOrExpression != null && isDynamicConcatenation(initializerOrExpression))
							|| reassignments.stream()
									.anyMatch(CMICSQLInjectionCheckCustomRule::isDynamicPlusAssignment)) {
						reportIssue(sqlArg, MAIN_MESSAGE,
								secondaryLocations(initializerOrExpression, reassignments, identifierTree.name()),
								null);
					}
				}
			}
		}
	}

	private static List<JavaFileScannerContext.Location> secondaryLocations(
			@Nullable ExpressionTree initializerOrExpression, List<AssignmentExpressionTree> reassignments,
			String identifierName) {
		List<JavaFileScannerContext.Location> secondaryLocations = reassignments.stream()
				.map(assignment -> new JavaFileScannerContext.Location(
						String.format("SQL Query is assigned to '%s'", getVariableName(assignment)),
						assignment.expression()))
				.collect(Collectors.toList());

		if (initializerOrExpression != null) {
			secondaryLocations.add(new JavaFileScannerContext.Location(
					String.format("SQL Query is dynamically formatted and assigned to '%s'", identifierName),
					initializerOrExpression));
		}
		return secondaryLocations;
	}

	private static String getVariableName(AssignmentExpressionTree assignment) {
		ExpressionTree variable = assignment.variable();
		return ((IdentifierTree) variable).name();
	}

	private static Stream<ExpressionTree> arguments(Tree methodTree) {
		if (methodTree.is(Tree.Kind.METHOD_INVOCATION)) {
			return ((MethodInvocationTree) methodTree).arguments().stream();
		}
		if (methodTree.is(Tree.Kind.NEW_CLASS)) {
			return ((NewClassTree) methodTree).arguments().stream();
		}
		return Stream.empty();
	}

	private static boolean anyMatch(Tree tree) {
		if (!hasArguments(tree)) {
			return false;
		}
		if (tree.is(Tree.Kind.NEW_CLASS)) {
			return SQL_INJECTION_SUSPECTS.matches((NewClassTree) tree);
		}
		if (tree.is(Tree.Kind.METHOD_INVOCATION)) {
			return SQL_INJECTION_SUSPECTS.matches((MethodInvocationTree) tree);
		}
		return false;
	}

	private static boolean hasArguments(Tree tree) {
		return arguments(tree).findAny().isPresent();
	}

	private static boolean isDynamicPlusAssignment(ExpressionTree arg) {
		return arg.is(Tree.Kind.PLUS_ASSIGNMENT)
				&& !((AssignmentExpressionTree) arg).expression().asConstant().isPresent();
	}

	private static boolean isDynamicConcatenation(ExpressionTree arg) {
		return arg.is(Tree.Kind.PLUS) && !arg.asConstant().isPresent();
	}

}
