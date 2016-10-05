// Compiler name mangling transformation tools.

#include "mangle.h"

#include <sdk/MacroUtils.h>

#include <cctype>

// Helpful docs:
//  https://github.com/gchatelet/gcc_cpp_mangling_documentation

// GCC mangling operator symbols.
#define GCC_OPSYMB_NEW                  "nw"
#define GCC_OPSYMB_NEW_ARRAY            "na"
#define GCC_OPSYMB_DELETE               "dl"
#define GCC_OPSYMB_DELETE_ARRAY         "da"
#define GCC_OPSYMB_PLUS                 "pl"
#define GCC_OPSYMB_MINUS                "mi"
#define GCC_OPSYMB_NEG                  "co"
#define GCC_OPSYMB_MULTIPLY             "ml"
#define GCC_OPSYMB_DIVIDE               "dv"
#define GCC_OPSYMB_REMAINDER            "rm"
#define GCC_OPSYMB_AND                  "an"
#define GCC_OPSYMB_OR                   "or"
#define GCC_OPSYMB_XOR                  "eo"
#define GCC_OPSYMB_ASSIGN               "aS"
#define GCC_OPSYMB_PLUS_ASSIGN          "pL"
#define GCC_OPSYMB_MINUS_ASSIGN         "mI"
#define GCC_OPSYMB_MULTIPLY_ASSIGN      "mL"
#define GCC_OPSYMB_DIVIDE_ASSIGN        "dV"
#define GCC_OPSYMB_REMAINDER_ASSIGN     "rM"
#define GCC_OPSYMB_AND_ASSIGN           "aN"
#define GCC_OPSYMB_OR_ASSIGN            "oR"
#define GCC_OPSYMB_XOR_ASSIGN           "eO"
#define GCC_OPSYMB_LEFT_SHIFT           "ls"
#define GCC_OPSYMB_RIGHT_SHIFT          "rs"
#define GCC_OPSYMB_LEFT_SHIFT_ASSIGN    "lS"
#define GCC_OPSYMB_RIGHT_SHIFT_ASSIGN   "rS"
#define GCC_OPSYMB_EQUALITY             "eq"
#define GCC_OPSYMB_INEQUALITY           "ne"
#define GCC_OPSYMB_LESS_THAN            "lt"
#define GCC_OPSYMB_GREATER_THAN         "gt"
#define GCC_OPSYMB_LESSEQ_THAN          "le"
#define GCC_OPSYMB_GREATEREQ_THAN       "ge"
#define GCC_OPSYMB_NOT                  "nt"
#define GCC_OPSYMB_LOGICAL_AND          "aa"
#define GCC_OPSYMB_LOGICAL_OR           "oo"
#define GCC_OPSYMB_INCREMENT            "pp"
#define GCC_OPSYMB_DECREMENT            "mm"
#define GCC_OPSYMB_COMMA                "cm"
#define GCC_OPSYMB_POINTER_RESOLUTION   "pm"
#define GCC_OPSYMB_POINTER              "pt"
#define GCC_OPSYMB_ROUND_BRACKETS       "cl"
#define GCC_OPSYMB_SQUARE_BRACKETS      "ix"
#define GCC_OPSYMB_QUESTIONMARK         "qu"
#define GCC_OPSYMB_SIZEOF               "st"
#define GCC_OPSYMB_SIZEOF2              "sz"
#define GCC_OPSYMB_CAST                 "cv"

// GCC mangling type sequences.
#define GCC_TYPESYMB_VOID               'v'
#define GCC_TYPESYMB_WCHAR_T            'w'
#define GCC_TYPESYMB_BOOL               'b'
#define GCC_TYPESYMB_CHAR               'c'
#define GCC_TYPESYMB_SIGNED_CHAR        'a'
#define GCC_TYPESYMB_UNSIGNED_CHAR      'h'
#define GCC_TYPESYMB_SHORT              's'
#define GCC_TYPESYMB_UNSIGNED_SHORT     't'
#define GCC_TYPESYMB_INT                'i'
#define GCC_TYPESYMB_UNSIGNED_INT       'j'
#define GCC_TYPESYMB_LONG               'l'
#define GCC_TYPESYMB_UNSIGNED_LONG      'm'
#define GCC_TYPESYMB_LONG_LONG          'x'
#define GCC_TYPESYMB_UNSIGNED_LONG_LONG 'y'
#define GCC_TYPESYMB_INT128             'n'
#define GCC_TYPESYMB_UNSIGNED_INT128    'o'
#define GCC_TYPESYMB_FLOAT              'f'
#define GCC_TYPESYMB_DOUBLE             'd'
#define GCC_TYPESYMB_LONG_DOUBLE        'e'
#define GCC_TYPESYMB_FLOAT128           'g'
#define GCC_TYPESYMB_ELLIPSIS           'z'
#define GCC_TYPESYMB_VENDOR             'u'

// GCC mangling type qualifiers.
#define GCC_TYPEQUALSYMB_POINTER        "P"
#define GCC_TYPEQUALSYMB_REFERENCE      "R"
#define GCC_TYPEQUALSYMB_RVAL_REFERENCE "O"
#define GCC_TYPEQUALSYMB_VENDOR         "U"

symbolType_t symbolicNamespace_t::ResolveParsePoint( void ) const
{
    // TODO: maybe make this more complicated.
    if ( this->nsType != eType::NAME )
    {
        throw mangle_parse_error();
    }

    // Get the deepest parse node.
    const symbolicNamespace_t *deepestNode = this;

    while ( const symbolicNamespace_t *prevSpace = deepestNode->parentResolve )
    {
        deepestNode = prevSpace;
    }

    // We return a basic type declaring us.
    symbolTypeSuit_regular_t valueBasic;
    valueBasic.valueType = eSymbolValueType::CUSTOM;
    
    // Go up the deepest node again.
    while ( true )
    {
        bool breakNow = ( deepestNode == this );

        assert( deepestNode != NULL );

        valueBasic.extTypeName.push_back( deepestNode->makeAttributeClone() );

        if ( breakNow )
        {
            break;
        }

        deepestNode = deepestNode->resolvedBy;
    }

    return valueBasic;
}

static AINLINE bool stracquire( const char*& strIn, const char *compWith )
{
    const char *str = strIn;

    while ( true )
    {
        char left = *str;
        char right = *compWith++;

        if ( right == 0 )
        {
            break;
        }

        str++;
        
        if ( left == 0 )
        {
            return false;
        }

        if ( left != right )
            return false;
    }

    strIn = str;
    return true;
}

static AINLINE bool _ParseMangleNumeric( const char*& streamIn, unsigned long& numOut )
{
    char c = *streamIn;

    if ( std::isdigit( c ) )
    {
        std::string numstr; 

        // Named definition.
        do
        {
            numstr += c;

            c = *++streamIn;

        } while ( std::isdigit( c ) );

        // Parse the count.
        numOut = std::stoul( numstr );
        return true;
    }
    
    return false;
}

static AINLINE bool _ParseMangleBoundString( const char*& streamIn, std::string& nameOut )
{
    unsigned long countName;
                
    if ( _ParseMangleNumeric( streamIn, countName ) )
    {
        // Read the name encoded string.
        std::string namestr;

        while ( countName-- )
        {
            char c = *streamIn;

            if ( c == 0 )
                throw mangle_parse_error();

            streamIn++;

            namestr += c;
        }

        nameOut = std::move( namestr );
        return true;
    }

    return false;
}

static inline symbolType_t BrowseSubstitution(
    unsigned long substIndex, 
    const SymbolCollection& collection
)
{
    LIST_FOREACH_BEGIN( symbolParsePoint_t, collection.parsePoints.root, parseNode )

        // If we are a constant value, we first try the non-constant portion.
        if ( item->isConstant() )
        {
            if ( substIndex == 0 )
            {
                symbolType_t symbOut = item->ResolveParsePoint();

                assert( symbOut.typeSuit != NULL );

                symbOut.typeSuit->makeConstant();
                return symbOut;
            }

            substIndex--;
        }

        if ( substIndex == 0 )
        {
            return item->ResolveParsePoint();
        }

        substIndex--;               

    LIST_FOREACH_END
    
    // We fail.
    throw mangle_parse_error();
}

// Special browsing routine used in namespace resolution.
static inline symbolicNamespace_t BrowseSubstitutionNamespace(
    unsigned long substIndex, 
    const SymbolCollection& collection
)
{
    LIST_FOREACH_BEGIN( symbolParsePoint_t, collection.parsePoints.root, parseNode )

        // We only count namespaces.
        if ( symbolicNamespace_t *nsEntry = dynamic_cast <symbolicNamespace_t*> ( item ) )
        {
            if ( substIndex == 0 )
            {
                return nsEntry->makeAttributeClone();
            }

            substIndex--;
        }

    LIST_FOREACH_END
    
    // We fail.
    throw mangle_parse_error();
}

// Forward declaration.
static inline symbolType_t _GCCParseMangledSymbolType(
    const char*& gccStream,
    SymbolCollection& collection
);

static AINLINE bool _GCCParseTypeInstancing(
    const char*& gccStream,
    SymbolCollection& collection,
    symbolicTemplateParams_t& argsOut
)
{
    if ( stracquire( gccStream, "I" ) )
    {
        symbolicTemplateParams_t templateArgs;

        bool isInLiteralMode = false;

        while ( true )
        {
            char c = *gccStream;

            if ( c == 0 )
                throw mangle_parse_error();

            if ( c == 'E' )
            {
                gccStream++;

                if ( isInLiteralMode )
                {
                    isInLiteralMode = false;
                }
                else
                {
                    break;
                }
            }
            else if ( stracquire( gccStream, "L" ) )
            {
                if ( isInLiteralMode )
                    throw mangle_parse_error();

                isInLiteralMode = true;
            }
            else
            {
                symbolicTemplateArg_t argPut;

                if ( isInLiteralMode )
                {
                    argPut.type = symbolicTemplateArg_t::eType::LITERAL;

                    symbolicLiteral_t litOut;

                    char typechar = *gccStream;

#define GCC_LITSYMB_HELPER( name_id ) \
    if ( typechar == GCC_TYPESYMB_##name_id ) \
    { \
        litOut.literalType = eSymbolValueType::##name_id##; \
        gccStream++; \
    }

                    // We can scan a lot of literal types.
                         GCC_LITSYMB_HELPER( VOID )
                    else GCC_LITSYMB_HELPER( WCHAR_T )
                    else GCC_LITSYMB_HELPER( BOOL )
                    else GCC_LITSYMB_HELPER( CHAR )
                    else GCC_LITSYMB_HELPER( UNSIGNED_CHAR )
                    else GCC_LITSYMB_HELPER( SHORT )
                    else GCC_LITSYMB_HELPER( UNSIGNED_SHORT )
                    else GCC_LITSYMB_HELPER( INT )
                    else GCC_LITSYMB_HELPER( UNSIGNED_INT )
                    else GCC_LITSYMB_HELPER( LONG )
                    else GCC_LITSYMB_HELPER( UNSIGNED_LONG )
                    else GCC_LITSYMB_HELPER( LONG_LONG )
                    else GCC_LITSYMB_HELPER( UNSIGNED_LONG_LONG )
                    else GCC_LITSYMB_HELPER( INT128 )
                    else GCC_LITSYMB_HELPER( UNSIGNED_INT128 )
                    else GCC_LITSYMB_HELPER( FLOAT )
                    else GCC_LITSYMB_HELPER( DOUBLE )
                    else GCC_LITSYMB_HELPER( LONG_DOUBLE )
                    else GCC_LITSYMB_HELPER( FLOAT128 )
                    else GCC_LITSYMB_HELPER( ELLIPSIS )
                    else
                    {
                        // Unknown literal symbol.
                        throw mangle_parse_error();
                    }

                    // Next we parse the literal value.
                    unsigned long litVal;

                    bool gotValue = _ParseMangleNumeric( gccStream, litVal );

                    if ( !gotValue )
                    {
                        throw mangle_parse_error();
                    }

                    litOut.literalValue = litVal;

                    // Store it.
                    argPut.ptr = new symbolicLiteral_t( std::move( litOut ) );
                }
                else
                {
                    argPut.type = symbolicTemplateArg_t::eType::TYPE;

                    symbolType_t typeOut = _GCCParseMangledSymbolType( gccStream, collection );

                    argPut.ptr = new symbolType_t( std::move( typeOut ) );
                }

                // Register it.
                templateArgs.push_back( std::move( argPut ) );
            }
        }

        argsOut = std::move( templateArgs );
        return true;
    }

    return false;
}

static AINLINE bool _GCCParseOneOperator(
    const char*& gccStream,
    eOperatorType& opTypeOut, symbolType_t& castToOut,
    SymbolCollection& collection
)
{
#define GCC_OPSYMB_HELPER( symb_id ) \
    if ( stracquire( gccStream, GCC_OPSYMB_##symb_id ) ) \
    { \
        opTypeOut = eOperatorType::##symb_id##; \
        return true; \
    }

         GCC_OPSYMB_HELPER( NEW )
    else GCC_OPSYMB_HELPER( NEW_ARRAY )
    else GCC_OPSYMB_HELPER( DELETE )
    else GCC_OPSYMB_HELPER( DELETE_ARRAY )
    else GCC_OPSYMB_HELPER( OR )
    else GCC_OPSYMB_HELPER( AND )
    else GCC_OPSYMB_HELPER( NEG )
    else GCC_OPSYMB_HELPER( XOR )
    else GCC_OPSYMB_HELPER( PLUS )
    else GCC_OPSYMB_HELPER( MINUS )
    else GCC_OPSYMB_HELPER( MULTIPLY )
    else GCC_OPSYMB_HELPER( DIVIDE )
    else GCC_OPSYMB_HELPER( REMAINDER )
    else GCC_OPSYMB_HELPER( ASSIGN )
    else GCC_OPSYMB_HELPER( PLUS_ASSIGN )
    else GCC_OPSYMB_HELPER( MINUS_ASSIGN )
    else GCC_OPSYMB_HELPER( MULTIPLY_ASSIGN )
    else GCC_OPSYMB_HELPER( DIVIDE_ASSIGN )
    else GCC_OPSYMB_HELPER( REMAINDER_ASSIGN )
    else GCC_OPSYMB_HELPER( AND_ASSIGN )
    else GCC_OPSYMB_HELPER( OR_ASSIGN )
    else GCC_OPSYMB_HELPER( XOR_ASSIGN )
    else GCC_OPSYMB_HELPER( LEFT_SHIFT )
    else GCC_OPSYMB_HELPER( RIGHT_SHIFT )
    else GCC_OPSYMB_HELPER( LEFT_SHIFT_ASSIGN )
    else GCC_OPSYMB_HELPER( RIGHT_SHIFT_ASSIGN )
    else GCC_OPSYMB_HELPER( EQUALITY )
    else GCC_OPSYMB_HELPER( INEQUALITY )
    else GCC_OPSYMB_HELPER( LESS_THAN )
    else GCC_OPSYMB_HELPER( GREATER_THAN )
    else GCC_OPSYMB_HELPER( LESSEQ_THAN )
    else GCC_OPSYMB_HELPER( GREATEREQ_THAN )
    else GCC_OPSYMB_HELPER( NOT )
    else GCC_OPSYMB_HELPER( LOGICAL_AND )
    else GCC_OPSYMB_HELPER( LOGICAL_OR )
    else GCC_OPSYMB_HELPER( INCREMENT )
    else GCC_OPSYMB_HELPER( DECREMENT )
    else GCC_OPSYMB_HELPER( COMMA )
    else GCC_OPSYMB_HELPER( POINTER_RESOLUTION )
    else GCC_OPSYMB_HELPER( POINTER )
    else GCC_OPSYMB_HELPER( ROUND_BRACKETS )
    else GCC_OPSYMB_HELPER( SQUARE_BRACKETS )
    else GCC_OPSYMB_HELPER( SIZEOF )
    else if ( stracquire( gccStream, GCC_OPSYMB_CAST ) )
    {
        opTypeOut = eOperatorType::CAST_TO;

        // We need to read the type aswell.
        castToOut = _GCCParseMangledSymbolType( gccStream, collection );

        return true;
    }
    
    return false;
}

static AINLINE bool _GCCParseNamespacePath(
    const char*& gccStream, SymbolCollection& symbCollect,
    symbolicNamespace_t::symbolicNamespaces_t& nsOut,
    bool& isConstNamespaceOut
)
{
    // Check for special qualifiers.
    if ( stracquire( gccStream, "N" ) == false )
        return false;

    // Check for further qualifier depending on class-things.
    bool isConstNamespace = false;

    if ( stracquire( gccStream, "K" ) )
    {
        isConstNamespace = true;
    }

    // Read the namespace names.
    symbolicNamespace_t::symbolicNamespaces_t namespaces;

    bool shouldRegisterLastNamespace = false;

    while ( true )
    {
        char c = *gccStream;

        if ( c == 0 )
            throw mangle_parse_error();

        // If we are a class namespace thing, we get terminated by a special symbol.
        if ( c == 'E' )
        {
            gccStream++;
            break;
        }

        bool gotNamespace = false;
        symbolicNamespace_t ns;

        // If we previously registered a namespace, we should remember it for resolution.
        // This will register all such namespaces other than the last.
        if ( shouldRegisterLastNamespace )
        {
            symbolicNamespace_t& lastNS = namespaces.back();

            // Register it.
            symbCollect.RegisterParsePoint( lastNS );

            shouldRegisterLastNamespace = false;

            // Maybe we have template parameters to attach...?
            symbolicTemplateParams_t templateArgs;

            if ( _GCCParseTypeInstancing( gccStream, symbCollect, templateArgs ) )
            {
                // Store it inside our namespace.
                lastNS.templateArgs = std::move( templateArgs );
            }

            // Register the resolution link.
            lastNS.setParentResolve( ns );
        }

        std::string namestr;
                
        if ( _ParseMangleBoundString( gccStream, namestr ) )
        {
            // Add this namespace entry.
            ns.nsType = symbolicNamespace_t::eType::NAME;
            ns.name = std::move( namestr );

            gotNamespace = true;
        }
        else
        {
            // Some other kind of entry, could be an operator descriptor.
            eOperatorType opType;
            symbolType_t castToType;

            if ( _GCCParseOneOperator( gccStream, opType, castToType, symbCollect ) )
            {
                ns.nsType = symbolicNamespace_t::eType::OPERATOR;
                ns.opType = opType;
                ns.opCastToType = std::move( castToType );

                gotNamespace = true;
            }
            else
            {
                // If not an operator, we try checking for special reserved method names.
                if ( stracquire( gccStream, "C" ) )
                {
                    // Make sure we have namespace entries.
                    if ( namespaces.empty() )
                        throw mangle_parse_error();

                    ns.nsType = symbolicNamespace_t::eType::NAME;
                    ns.name = namespaces.back().name;

                    // There should be a number, no idea why.
                    unsigned long unkNum;

                    _ParseMangleNumeric( gccStream, unkNum );

                    gotNamespace = true;
                }
                else if ( stracquire( gccStream, "D" ) )
                {
                    // Destructor.
                    if ( namespaces.empty() )
                        throw mangle_parse_error();

                    ns.nsType = symbolicNamespace_t::eType::NAME;
                    ns.name = "~" + namespaces.back().name;

                    // Ignore number.
                    unsigned long unkNum;

                    _ParseMangleNumeric( gccStream, unkNum );

                    gotNamespace = true;
                }
                else
                {
                    // We have very limited substitution support here.
                    if ( stracquire( gccStream, "S" ) )
                    {
                        unsigned long substIndex = 0;

                        if ( _ParseMangleNumeric( gccStream, substIndex ) )
                        {
                            substIndex++;
                        }

                        if ( stracquire( gccStream, "_" ) == false )
                        {
                            throw mangle_parse_error();
                        }

                        // TODO: for now I don't give a flying donkeys ass that GCC
                        // name mangling substitution allows spawning of more than one
                        // namespace entry per substitution token.

                        // Browse for a substitution namespace definition.
                        symbolicNamespace_t substance = BrowseSubstitutionNamespace( substIndex, symbCollect );

                        // We take its attributes.
                        ns.nsType = symbolicNamespace_t::eType::NAME;
                        ns.name = std::move( substance.name );

                        gotNamespace = true;
                    }
                }

                // TODO: add more.
            }
        }

        if ( !gotNamespace )
        {
            // If we are a class namespace, this is not good.
            throw mangle_parse_error();
        }

        // Remember to register last namespace.
        shouldRegisterLastNamespace = true;

        namespaces.push_back( std::move( ns ) );

        // Done with single namespace
    }

    // Done reading namespaces.
    // We must have at least one namespace.
    if ( namespaces.empty() )
        throw mangle_parse_error();

    // Return stuff.
    nsOut = std::move( namespaces );
    isConstNamespaceOut = isConstNamespace;
    return true;
}

static inline symbolType_t _GCCParseMangledSymbolType(
    const char*& gccStream, SymbolCollection& collection
)
{
    symbolType_t typeOut( NULL );

    // Are we constant?
    bool isConstant = false;

    if ( stracquire( gccStream, "K" ) )
    {
        isConstant = true;
    }

    // Parse a type in the stream, one by one.
    {
        // Check if we are a substitution.
        // Then we have to return a type we already created before.
        if ( stracquire( gccStream, "S" ) )
        {
            // Parse a number that we will use as index.
            unsigned long indexNum = 0;

            bool gotNumeric = _ParseMangleNumeric( gccStream, indexNum );

            if ( gotNumeric )
            {
                // In that case we increase by one.
                indexNum++;
            }

            // We need to end with a special symbol.
            bool gotSpecSymb = stracquire( gccStream, "_" );

            if ( !gotSpecSymb )
            {
                throw mangle_parse_error();
            }

            // We index the already available types.
            typeOut = BrowseSubstitution( indexNum, collection );
        }
        else
        {
            // There are multiple suits of types.
            if ( stracquire( gccStream, "F" ) )
            {
                if ( *gccStream == 0 )
                    throw mangle_parse_error();

                // We found a function type.
                // It starts with the return type and then the remainder (until end marker)
                // are all the parameters.

                symbolTypeSuit_function_t suitOut;

                suitOut.returnType = _GCCParseMangledSymbolType( gccStream, collection );

                while ( true )
                {
                    char c = *gccStream;

                    if ( c == 0 )
                        throw mangle_parse_error();

                    if ( c == 'E' )
                    {
                        gccStream++;
                        break;
                    }

                    symbolType_t paramType = _GCCParseMangledSymbolType( gccStream, collection );

                    suitOut.parameters.push_back( std::move( paramType ) );
                }

                // I guess GCC does not care about calling conventions.

                // Return it.
                typeOut.typeSuit = new symbolTypeSuit_function_t( std::move( suitOut ) );
            }
            else if ( stracquire( gccStream, "A" ) )
            {
                // Array suit.
                symbolTypeSuit_array_t suitOut;

                unsigned long arraySize;

                bool hasArraySize = _ParseMangleNumeric( gccStream, arraySize );

                if ( hasArraySize )
                {
                    suitOut.sizeOfArray = arraySize;
                }

                bool hasTerminator = stracquire( gccStream, "_" );

                if ( !hasTerminator )
                {
                    throw mangle_parse_error();
                }

                suitOut.hasIndex = hasArraySize;

                suitOut.typeOfItem = _GCCParseMangledSymbolType( gccStream, collection );

                // Return it.
                typeOut.typeSuit = new symbolTypeSuit_array_t( std::move( suitOut ) );
            }
            else
            {
                // By default we have the "regular" suit.
                symbolTypeSuit_regular_t suitOut;

                suitOut.isConst = isConstant;

                // Check for a valid type prefix.
                eSymbolTypeQualifier qual = eSymbolTypeQualifier::VALUE;

                if ( stracquire( gccStream, GCC_TYPEQUALSYMB_POINTER ) )
                {
                    qual = eSymbolTypeQualifier::POINTER;
                }
                else if ( stracquire( gccStream, GCC_TYPEQUALSYMB_REFERENCE ) )
                {
                    qual = eSymbolTypeQualifier::REFERENCE;
                }
                else if ( stracquire( gccStream, GCC_TYPEQUALSYMB_RVAL_REFERENCE ) )
                {
                    qual = eSymbolTypeQualifier::RVAL_REFERENCE;
                }

                suitOut.valueQual = qual;

                // If we are not a value qualifier, then we have to have a subtype.
                if ( qual != eSymbolTypeQualifier::VALUE )
                {
                    symbolType_t subtype = _GCCParseMangledSymbolType( gccStream, collection );

                    suitOut.subtype = new symbolType_t( std::move( subtype ) );
                }
                else
                {
                    // Else we are a type ourselves.
                    char typechar = *gccStream;

#define GCC_TYPESYMB_HELPER( name_id ) \
    if ( typechar == GCC_TYPESYMB_##name_id ) \
    { \
        suitOut.valueType = eSymbolValueType::##name_id; \
        gccStream++; \
    }

                         GCC_TYPESYMB_HELPER( VOID )
                    else GCC_TYPESYMB_HELPER( WCHAR_T )
                    else GCC_TYPESYMB_HELPER( BOOL )
                    else GCC_TYPESYMB_HELPER( CHAR )
                    else if ( typechar == 'a' )
                    {
                        suitOut.valueType = eSymbolValueType::CHAR;
                        gccStream++;
                    }
                    else GCC_TYPESYMB_HELPER( UNSIGNED_CHAR )
                    else GCC_TYPESYMB_HELPER( SHORT )
                    else GCC_TYPESYMB_HELPER( UNSIGNED_SHORT )
                    else GCC_TYPESYMB_HELPER( INT )
                    else GCC_TYPESYMB_HELPER( UNSIGNED_INT )
                    else GCC_TYPESYMB_HELPER( LONG )
                    else GCC_TYPESYMB_HELPER( UNSIGNED_LONG )
                    else GCC_TYPESYMB_HELPER( LONG_LONG )
                    else GCC_TYPESYMB_HELPER( UNSIGNED_LONG_LONG )
                    else GCC_TYPESYMB_HELPER( INT128 )
                    else GCC_TYPESYMB_HELPER( UNSIGNED_INT128 )
                    else GCC_TYPESYMB_HELPER( FLOAT )
                    else GCC_TYPESYMB_HELPER( DOUBLE )
                    else GCC_TYPESYMB_HELPER( LONG_DOUBLE )
                    else GCC_TYPESYMB_HELPER( FLOAT128 )
                    else GCC_TYPESYMB_HELPER( ELLIPSIS )
                    else
                    {
                        // If we are not one of the built-in types,
                        // we could be a custom type name!
                        std::string namestr;

                        if ( _ParseMangleBoundString( gccStream, namestr ) )
                        {
                            // Register it.
                            suitOut.valueType = eSymbolValueType::CUSTOM;

                            symbolicNamespace_t ns;
                            ns.name = std::move( namestr );

                            suitOut.extTypeName.push_back( std::move( ns ) );
                        }
                        else
                        {
                            // Maybe a full namespace path?
                            symbolicNamespace_t::symbolicNamespaces_t namespaces;
                            bool isConstantNamespace;   // we ignore that because it makes zero sense.

                            if ( _GCCParseNamespacePath( gccStream, collection, namespaces, isConstantNamespace ) )
                            {
                                // Remember that we now accept the last namespace entry too, so register it.
                                collection.RegisterParsePoint( namespaces.back() );

                                suitOut.valueType = eSymbolValueType::CUSTOM;

                                suitOut.extTypeName = std::move( namespaces );
                            }
                            else
                            {
                                // Not supported or unknown.
                                throw mangle_parse_error();
                            }
                        }
                    }
                }

                // Finished processing the type suit, now try putting it into our type.
                typeOut.typeSuit = new symbolTypeSuit_regular_t( std::move( suitOut ) );
            }
        }
    }

    // Process the type suit.
    symbolTypeSuit_t *typeSuit = typeOut.typeSuit;

    assert( typeSuit != NULL );

    // Maybe we have to be made constant?
    if ( isConstant )
    {
        typeSuit->makeConstant();
    }

    // We could be followed by template arguments.
    {
        symbolicTemplateParams_t templateArgs;

        if ( _GCCParseTypeInstancing( gccStream, collection, templateArgs ) )
        {
            // Store them.
            typeSuit->giveTemplateArguments( std::move( templateArgs ) );
        }
    }

    // We want to remember complicated types for compressed lookup.
    if ( typeSuit->isComplicated() )
    {
        // Register this encountered symbol.
        collection.RegisterParsePoint( typeOut );
    }

    return typeOut;
}

bool ProgFunctionSymbol::ParseMangled( const char *codecStream )
{
    // Read any stream of mangled-ness into our storage.
    // * GCC.
    try
    {
        // Variable const qual: L
        // Class decl start: N
        // Class decl end: E
        // Class method const qual: K
        // Class constructor: C[:num:]

        const char *gccStream = codecStream;

        // Test the prefix.
        if ( stracquire( gccStream, "_Z" ) )
        {
            char begDec = *gccStream;

            bool isMultiNamespace = false;
            bool isClassMethodConst = false;

            // We need this for the substitution lookup.
            SymbolCollection symbCollect;

            // Read the namespace names.
            symbolicNamespace_t::symbolicNamespaces_t namespaces;

            if ( _GCCParseNamespacePath( gccStream, symbCollect, namespaces, isClassMethodConst ) )
            {
                // Done here.
            }
            else
            {
                std::string namestr;

                if ( _ParseMangleBoundString( gccStream, namestr ) )
                {
                    // Add this namespace entry.
                    symbolicNamespace_t ns;
                    ns.nsType = symbolicNamespace_t::eType::NAME;
                    ns.name = std::move( namestr );

                    namespaces.push_back( std::move( ns ) );
                }
                else
                {
                    // We could also be an operator.
                    eOperatorType opType;
                    symbolType_t opCastToType;

                    if ( _GCCParseOneOperator( gccStream, opType, opCastToType, symbCollect ) )
                    {
                        // Alright.
                        symbolicNamespace_t ns;
                        ns.nsType = symbolicNamespace_t::eType::OPERATOR;
                        ns.opType = std::move( opType );
                        ns.opCastToType = std::move( opCastToType );

                        namespaces.push_back( std::move( ns ) );
                    }
                    else
                    {
                        // Ignore vtable errors, because we focus on function symbols.
                        if ( stracquire( gccStream, "T" ) )
                        {
                            // Do not care.
                            throw mangle_parse_error();
                        }
                        else
                        {
                            // Invalid.
                            throw mangle_parse_error();
                        }
                    }
                }
            }

            // Now we read the parameter types.
            std::vector <symbolType_t> arguments;

            while ( *gccStream != 0 )
            {
                symbolType_t paramType = _GCCParseMangledSymbolType( gccStream, symbCollect );

                // Add it.
                arguments.push_back( std::move( paramType ) );
            }

            // Success!
            this->callingConv = ( isMultiNamespace ? eSymbolCallConv::THISCALL : eSymbolCallConv::CDECL );
            this->namespaces = std::move( namespaces );
            this->arguments = std::move( arguments );
            this->hasConstQualifier = isClassMethodConst;

            return true;
        }
    }
    catch( mangle_parse_error& )
    {}

    // * Visual Studio
    {
        //TODO.
    }

    // None detected.
    return false;
}

std::string ProgFunctionSymbol::OutputMangled( eManglingType type )
{
    if ( type == eManglingType::GCC )
    {
        // GNU Compiler Collection mangling system.
    }
    else if ( type == eManglingType::VISC )
    {
        // Microsoft Visual C++ mangling system.
    }

    // Not supported yet.
    return std::string();
}