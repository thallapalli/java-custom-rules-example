package org.sonar.samples.java.checks;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;

import org.sonar.check.Rule;
import org.sonar.plugins.java.api.IssuableSubscriptionVisitor;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.MethodMatchers;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.AssignmentExpressionTree;
import org.sonar.plugins.java.api.tree.EnumConstantTree;
import org.sonar.plugins.java.api.tree.ExpressionTree;
import org.sonar.plugins.java.api.tree.IdentifierTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.Tree;
import org.sonar.plugins.java.api.tree.VariableTree;

@Rule(key = "CMICSQLInjectionCheckCustomRule")
public class CMICSQLInjectionCheckCustomRule extends IssuableSubscriptionVisitor {
	private static final String JAVA_SQL_STATEMENT = "java.sql.Statement";
	private static final String JAVA_SQL_STATEMENT_CALLABLE = "java.sql.CallableStatement";
	private static final String JAVA_SQL_CONNECTION = "java.sql.Connection";
	private static final String SPRING_JDBC_OPERATIONS = "org.springframework.jdbc.core.JdbcOperations";

	private static final MethodMatchers SQL_INJECTION_SUSPECTS = MethodMatchers.or(
			MethodMatchers.create().ofSubTypes("org.hibernate.Session").names("createQuery", "createSQLQuery")
					.withAnyParameters().build(),
			MethodMatchers.create().ofSubTypes(JAVA_SQL_STATEMENT)
					.names("executeQuery", "execute", "executeUpdate", "executeLargeUpdate", "addBatch","createCallableStatement")
					.withAnyParameters().build(),
					MethodMatchers.create().ofSubTypes(JAVA_SQL_STATEMENT_CALLABLE)
					.names("executeQuery", "execute", "executeUpdate", "executeLargeUpdate", "addBatch","createCallableStatement")
					.withAnyParameters().build(),
			MethodMatchers.create().ofSubTypes(JAVA_SQL_CONNECTION)
					.names("prepareStatement", "createCallableStatement", "prepareCall", "nativeSQL")
					.withAnyParameters().build(),
			MethodMatchers.create().ofTypes("javax.persistence.EntityManager").names("createNativeQuery", "createQuery")
					.withAnyParameters().build(),
			MethodMatchers.create().ofSubTypes(SPRING_JDBC_OPERATIONS)
					.names("batchUpdate", "execute", "query", "queryForList", "queryForMap", "queryForObject",
							"queryForRowSet", "queryForInt", "queryForLong", "update")
					.withAnyParameters().build(),

			MethodMatchers.create().ofSubTypes("javax.jdo.PersistenceManager").names("newQuery").withAnyParameters()
					.build(),

			MethodMatchers.create().ofSubTypes("javax.jdo.Query").names("setFilter", "setGrouping").withAnyParameters()
					.build(),
			
			MethodMatchers.create().ofAnyType().anyName().withAnyParameters().build(),
			MethodMatchers.create().ofAnyType().anyName().addWithoutParametersMatcher().build(),
			MethodMatchers.create().ofSubTypes("oracle.jbo.server.ApplicationModuleImpl").anyName().withAnyParameters().build(),
			MethodMatchers.create().ofTypes("((oracle.jbo.server.ApplicationModuleImpl)applicationModule).getDBTransaction()").anyName().withAnyParameters().build()
			
			/**,
			MethodMatchers.create().ofAnyType().names("createCallableStatement").build(),
			MethodMatchers.create().ofSubTypes("oracle.jbo.server.ApplicationModuleImpl").anyName().withAnyParameters().build(),
			MethodMatchers.create().ofSubTypes("oracle.jbo.server.ApplicationModuleImpl").anyName().addWithoutParametersMatcher().build(),
			MethodMatchers.create().ofSubTypes("oracle.jbo.server.ApplicationModuleImpl").anyName().addWithoutParametersMatcher().build()
			
			
			MethodMatchers.create().ofSubTypes("((oracle.jbo.server.ApplicationModuleImpl)applicationModule).getDBTransaction()").anyName().addWithoutParametersMatcher().build(),
			MethodMatchers.create().ofTypes("oracle.jbo.server.ApplicationModuleImpl").anyName().addWithoutParametersMatcher().build(),
			MethodMatchers.create().ofTypes("((oracle.jbo.server.ApplicationModuleImpl)applicationModule).getDBTransaction()").anyName().addWithoutParametersMatcher().build(),
			MethodMatchers.create().ofTypes("oracle.jbo.server.ApplicationModuleImpl").anyName().withAnyParameters().build(),
			MethodMatchers.create().ofTypes("((oracle.jbo.server.ApplicationModuleImpl)applicationModule).getDBTransaction()").anyName().withAnyParameters().build()
			**/
			
			
			
			
			
			
			

	);

	private static final String MAIN_MESSAGE = "Make sure using a dynamically formatted SQL query is safe here.";

	@Override
	public List<Tree.Kind> nodesToVisit() {
		return Arrays.asList(Tree.Kind.METHOD_INVOCATION, Tree.Kind.NEW_CLASS);
	}

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
						String.format("SQL Query is assigned to '%s' -Custom", getVariableName(assignment)),
						assignment.expression()))
				.collect(Collectors.toList());

		if (initializerOrExpression != null) {
			secondaryLocations.add(new JavaFileScannerContext.Location(
					String.format("SQL Query is dynamically formatted and assigned to '%s' -Custom", identifierName),
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

	public static List<AssignmentExpressionTree> getReassignments(@Nullable Tree ownerDeclaration,
			List<IdentifierTree> usages) {
		if (ownerDeclaration != null) {
			List<AssignmentExpressionTree> assignments = new ArrayList<>();
			for (IdentifierTree usage : usages) {
				checkAssignment(usage).ifPresent(assignments::add);
			}
			return assignments;
		}
		return new ArrayList<>();
	}

	private static Optional<AssignmentExpressionTree> checkAssignment(IdentifierTree usage) {
		Tree previousTree = usage;
		Tree nonParenthesisParent = previousTree.parent();

		while (nonParenthesisParent.is(Tree.Kind.PARENTHESIZED_EXPRESSION)) {
			previousTree = nonParenthesisParent;
			nonParenthesisParent = previousTree.parent();
		}

		if (nonParenthesisParent instanceof AssignmentExpressionTree) {
			AssignmentExpressionTree assignment = (AssignmentExpressionTree) nonParenthesisParent;
			if (assignment.variable().equals(previousTree)) {
				return Optional.of(assignment);
			}
		}
		return Optional.empty();
	}

	@CheckForNull
	public static ExpressionTree getInitializerOrExpression(@Nullable Tree tree) {
		if (tree == null) {
			return null;
		}
		if (tree.is(Tree.Kind.VARIABLE)) {
			return ((VariableTree) tree).initializer();
		} else if (tree.is(Tree.Kind.ENUM_CONSTANT)) {
			return ((EnumConstantTree) tree).initializer();
		} else if (tree instanceof AssignmentExpressionTree) {
			// All kinds of Assignment
			return ((AssignmentExpressionTree) tree).expression();
		}
		// Can be other declaration, like class
		return null;
	}
}
